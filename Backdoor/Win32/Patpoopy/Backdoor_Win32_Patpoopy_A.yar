
rule Backdoor_Win32_Patpoopy_A{
	meta:
		description = "Backdoor:Win32/Patpoopy.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 11 00 00 01 00 "
		
	strings :
		$a_80_0 = {50 75 70 79 50 61 63 6b 61 67 65 4c 6f 61 64 65 72 } //PupyPackageLoader  01 00 
		$a_80_1 = {50 75 70 79 50 61 63 6b 61 67 65 46 69 6e 64 65 72 } //PupyPackageFinder  01 00 
		$a_80_2 = {50 75 70 79 20 72 65 76 65 72 73 65 20 73 68 65 6c 6c 20 72 70 79 63 20 73 65 72 76 69 63 65 } //Pupy reverse shell rpyc service  01 00 
		$a_80_3 = {42 75 69 6c 74 69 6e 73 20 75 74 69 6c 69 74 69 65 73 20 66 6f 72 20 70 75 70 79 } //Builtins utilities for pupy  01 00 
		$a_80_4 = {70 75 70 79 69 6d 70 6f 72 74 65 72 } //pupyimporter  01 00 
		$a_80_5 = {70 75 70 79 5f 61 64 64 5f 70 61 63 6b 61 67 65 } //pupy_add_package  01 00 
		$a_80_6 = {6d 6f 64 75 6c 65 73 20 70 75 70 79 20 61 6e 64 20 5f 6d 65 6d 69 6d 70 6f 72 74 65 72 } //modules pupy and _memimporter  01 00 
		$a_80_7 = {69 6d 70 6f 72 74 20 70 75 70 79 } //import pupy  03 00 
		$a_80_8 = {6d 61 72 73 68 61 6c 2e 6c 6f 61 64 73 28 7a 6c 69 62 2e 64 65 63 6f 6d 70 72 65 73 73 28 70 75 70 79 2e 5f 67 65 74 5f 63 6f 6d 70 72 65 73 73 65 64 5f 6c 69 62 72 61 72 79 5f 73 74 72 69 6e 67 28 29 } //marshal.loads(zlib.decompress(pupy._get_compressed_library_string()  02 00 
		$a_80_9 = {72 65 74 75 72 6e 20 50 75 70 79 50 61 63 6b 61 67 65 4c 6f 61 64 65 72 28 66 75 6c 6c 6e 61 6d 65 2c 20 63 6f 6e 74 65 6e 74 2c 20 65 78 74 65 6e 73 69 6f 6e 2c 20 69 73 5f 70 6b 67 2c 20 73 65 6c 65 63 74 65 64 29 } //return PupyPackageLoader(fullname, content, extension, is_pkg, selected)  02 00 
		$a_80_10 = {70 75 70 79 5f 61 64 64 5f 70 61 63 6b 61 67 65 28 70 6b 64 69 63 29 } //pupy_add_package(pkdic)  02 00 
		$a_80_11 = {73 79 73 2e 6d 65 74 61 5f 70 61 74 68 2e 61 70 70 65 6e 64 28 50 75 70 79 50 61 63 6b 61 67 65 46 69 6e 64 65 72 28 6d 6f 64 75 6c 65 73 29 29 } //sys.meta_path.append(PupyPackageFinder(modules))  02 00 
		$a_80_12 = {70 6c 65 61 73 65 20 73 74 61 72 74 20 70 75 70 79 20 66 72 6f 6d 20 65 69 74 68 65 72 20 69 74 27 73 20 65 78 65 20 73 74 75 62 20 6f 72 20 69 74 27 73 20 72 65 66 6c 65 63 74 69 76 65 20 44 4c 4c } //please start pupy from either it's exe stub or it's reflective DLL  01 00 
		$a_80_13 = {00 67 65 74 5f 63 6f 6e 6e 65 63 74 5f 62 61 63 6b 5f 68 6f 73 74 00 } //  01 00 
		$a_80_14 = {00 67 65 74 5f 61 72 63 68 00 } //  01 00 
		$a_80_15 = {00 67 65 74 20 63 75 72 72 65 6e 74 20 70 75 70 79 20 61 72 63 68 69 74 65 63 74 75 72 65 20 28 78 38 36 20 6f 72 20 78 36 34 29 00 } //  01 00 
		$a_80_16 = {72 65 66 6c 65 63 74 69 76 65 5f 69 6e 6a 65 63 74 5f 64 6c 6c 28 70 69 64 2c 20 64 6c 6c 5f 62 75 66 66 65 72 2c 20 69 73 52 65 6d 6f 74 65 50 72 6f 63 65 73 73 36 34 62 69 74 73 29 } //reflective_inject_dll(pid, dll_buffer, isRemoteProcess64bits)  00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Patpoopy_A_2{
	meta:
		description = "Backdoor:Win32/Patpoopy.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 28 00 00 05 00 "
		
	strings :
		$a_00_0 = {00 70 75 70 79 78 36 34 2e 64 6c 6c 00 52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 00 } //05 00  瀀灵硹㐶搮汬刀晥敬瑣癩䱥慯敤r
		$a_00_1 = {00 70 75 70 79 78 36 34 2e 75 6e 63 2e 64 6c 6c 00 52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 00 } //05 00  瀀灵硹㐶甮据搮汬刀晥敬瑣癩䱥慯敤r
		$a_00_2 = {00 70 75 70 79 78 38 36 2e 64 6c 6c 00 5f 52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 40 34 00 } //05 00 
		$a_00_3 = {00 70 75 70 79 78 38 36 2e 75 6e 63 2e 64 6c 6c 00 5f 52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 40 34 00 } //02 00 
		$a_80_4 = {67 65 74 20 63 75 72 72 65 6e 74 20 70 75 70 79 20 61 72 63 68 69 74 65 63 74 75 72 65 20 28 78 38 36 20 6f 72 20 78 36 34 29 } //get current pupy architecture (x86 or x64)  02 00 
		$a_80_5 = {67 65 74 5f 70 75 70 79 5f 63 6f 6e 66 69 67 } //get_pupy_config  02 00 
		$a_80_6 = {00 70 75 70 79 2e 65 72 72 6f 72 00 } //  02 00 
		$a_80_7 = {42 75 69 6c 74 69 6e 73 20 75 74 69 6c 69 74 69 65 73 20 66 6f 72 20 70 75 70 79 } //Builtins utilities for pupy  02 00 
		$a_80_8 = {23 23 23 23 2d 2d 2d 50 55 50 59 5f 43 4f 4e 46 49 47 5f 43 4f 4d 45 53 5f 48 45 52 45 2d 2d 2d 23 23 23 23 } //####---PUPY_CONFIG_COMES_HERE---####  01 00 
		$a_80_9 = {2f 6e 31 6e 6a 34 73 65 63 2f } ///n1nj4sec/  01 00 
		$a_80_10 = {40 6e 31 6e 6a 34 73 65 63 } //@n1nj4sec  01 00 
		$a_80_11 = {63 6f 6e 74 61 63 74 40 6e 31 6e 6a 34 2e 65 75 } //contact@n1nj4.eu  01 00 
		$a_80_12 = {5c 70 75 70 79 5c 6e 65 74 77 6f 72 6b 5c 6c 69 62 5c } //\pupy\network\lib\  01 00 
		$a_80_13 = {42 61 73 65 50 75 70 79 54 72 61 6e 73 70 6f 72 74 } //BasePupyTransport  01 00 
		$a_80_14 = {44 75 6d 6d 79 50 75 70 79 } //DummyPupy  01 00 
		$a_80_15 = {66 72 6f 6d 20 6e 65 74 77 6f 72 6b 2e 6c 69 62 2e 73 74 72 65 61 6d 73 2e 50 75 70 79 53 6f 63 6b 65 74 53 74 72 65 61 6d 20 69 6d 70 6f 72 74 20 50 75 70 79 43 68 61 6e 6e 65 6c } //from network.lib.streams.PupySocketStream import PupyChannel  01 00 
		$a_80_16 = {66 72 6f 6d 20 70 75 70 79 5f 63 72 65 64 65 6e 74 69 61 6c 73 20 69 6d 70 6f 72 74 20 42 49 4e 44 5f 50 41 59 4c 4f 41 44 53 5f 50 41 53 53 57 4f 52 44 } //from pupy_credentials import BIND_PAYLOADS_PASSWORD  01 00 
		$a_80_17 = {6d 6f 64 20 3d 20 69 6d 70 2e 6e 65 77 5f 6d 6f 64 75 6c 65 28 22 70 75 70 79 22 29 } //mod = imp.new_module("pupy")  01 00 
		$a_80_18 = {6d 6f 64 2e 5f 5f 66 69 6c 65 5f 5f 20 3d 20 22 70 75 70 79 3a 2f 2f 70 75 70 79 22 } //mod.__file__ = "pupy://pupy"  01 00 
		$a_80_19 = {6d 6f 64 2e 5f 5f 70 61 63 6b 61 67 65 5f 5f 20 3d 20 22 70 75 70 79 22 } //mod.__package__ = "pupy"  01 00 
		$a_80_20 = {50 75 70 79 20 72 65 76 65 72 73 65 20 73 68 65 6c 6c 20 72 70 79 63 20 73 65 72 76 69 63 65 } //Pupy reverse shell rpyc service  01 00 
		$a_80_21 = {70 75 70 79 2e 67 65 74 5f 63 6f 6e 6e 65 63 74 5f 62 61 63 6b 5f 68 6f 73 74 20 3d 20 28 6c 61 6d 62 64 61 3a 20 48 4f 53 54 29 } //pupy.get_connect_back_host = (lambda: HOST)  01 00 
		$a_80_22 = {70 75 70 79 2e 69 6e 66 6f 73 20 3d 20 7b 7d } //pupy.infos = {}  01 00 
		$a_80_23 = {70 75 70 79 3a 2f 2f 7b 7d } //pupy://{}  01 00 
		$a_80_24 = {70 75 70 79 5f 73 72 76 } //pupy_srv  01 00 
		$a_80_25 = {50 75 70 79 41 73 79 6e 63 } //PupyAsync  01 00 
		$a_80_26 = {50 75 70 79 43 44 4c 4c 2e 5f 66 69 6e 64 5f 66 75 6e 63 74 69 6f 6e 5f 61 64 64 72 65 73 73 3a 20 7b 7d 20 3d 20 7b 7d } //PupyCDLL._find_function_address: {} = {}  01 00 
		$a_80_27 = {50 75 70 79 43 6f 6e 6e 65 63 74 69 6f 6e } //PupyConnection  01 00 
		$a_80_28 = {50 75 70 79 48 54 54 50 } //PupyHTTP  01 00 
		$a_80_29 = {70 75 70 79 6c 69 62 2e 50 75 70 79 43 72 65 64 65 6e 74 69 61 6c 73 } //pupylib.PupyCredentials  01 00 
		$a_80_30 = {50 75 70 79 50 61 63 6b 61 67 65 4c 6f 61 64 65 72 3a } //PupyPackageLoader:  01 00 
		$a_80_31 = {50 75 70 79 50 72 6f 78 69 66 69 65 64 } //PupyProxified  01 00 
		$a_80_32 = {50 75 70 79 53 6f 63 6b 65 74 53 74 72 65 61 6d } //PupySocketStream  01 00 
		$a_80_33 = {50 75 70 79 53 53 4c 43 6c 69 65 6e 74 } //PupySSLClient  01 00 
		$a_80_34 = {50 75 70 79 54 43 50 } //PupyTCP  01 00 
		$a_80_35 = {50 75 70 79 55 44 50 } //PupyUDP  01 00 
		$a_80_36 = {50 75 70 79 57 65 62 53 6f 63 6b 65 74 } //PupyWebSocket  01 00 
		$a_80_37 = {72 65 6d 6f 74 65 5f 70 72 69 6e 74 5f 65 72 72 6f 72 20 3d 20 70 75 70 79 69 6d 70 6f 72 74 65 72 2e 72 65 6d 6f 74 65 5f 70 72 69 6e 74 5f 65 72 72 6f 72 } //remote_print_error = pupyimporter.remote_print_error  01 00 
		$a_80_38 = {73 65 74 61 74 74 72 28 70 75 70 79 2c 20 27 54 61 73 6b 27 2c 20 54 61 73 6b 29 } //setattr(pupy, 'Task', Task)  01 00 
		$a_80_39 = {73 79 73 2e 6d 6f 64 75 6c 65 73 5b 22 70 75 70 79 22 5d 20 3d 20 6d 6f 64 } //sys.modules["pupy"] = mod  00 00 
	condition:
		any of ($a_*)
 
}