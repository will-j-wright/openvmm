// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

macro_rules! get_active_registers {
    ($vp:expr, [$($name:expr),+ $(,)?] $(,)?) => {{
        let names = [$(whp::RegisterName::as_abi(&($name))),+];
        let mut values = [$({ let _ = &$name; whp::abi::WHV_REGISTER_VALUE::default() }),+];
        ($vp).get_active_registers(&names, &mut values).map(|_| {
            let mut vs = &values[..];
            #[expect(clippy::allow_attributes)]
            #[allow(unused_assignments)]
            ($({
                let n = $name;
                let v = &vs[0];
                vs = &vs[1..];
                { whp::extract_helper(n, v) }
            }),+)
        })
    }};
}

macro_rules! set_active_registers {
    ($vp:expr, [$(($name:expr, $value:expr)),+ $(,)?] $(,)?) => {{
        #[expect(clippy::allow_attributes)]
        #[allow(unused_parens)]
        {
            let names = [$(whp::RegisterName::as_abi(&($name))),+];
            let values = [$(whp::inject_helper(($name), &($value))),+];
            ($vp).set_active_registers(&names, &values)
        }
    }};
}

macro_rules! get_vtl_registers {
    ($vp:expr, $vtl:expr, [$($name:expr),+ $(,)?] $(,)?) => {{
        let names = [$(whp::RegisterName::as_abi(&($name))),+];
        let mut values = [$({ let _ = &$name; whp::abi::WHV_REGISTER_VALUE::default() }),+];
        ($vp).get_vtl_registers($vtl, &names, &mut values).map(|_| {
            let mut vs = &values[..];
            #[expect(clippy::allow_attributes)]
            #[allow(unused_assignments)]
            ($({
                let n = $name;
                let v = &vs[0];
                vs = &vs[1..];
                { whp::extract_helper(n, v) }
            }),+)
        })
    }};
}
