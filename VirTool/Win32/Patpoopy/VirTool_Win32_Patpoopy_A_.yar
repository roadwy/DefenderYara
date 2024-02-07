
rule VirTool_Win32_Patpoopy_A_{
	meta:
		description = "VirTool:Win32/Patpoopy.A!!Patpoopy.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_80_0 = {50 75 70 79 50 61 63 6b 61 67 65 4c 6f 61 64 65 72 } //PupyPackageLoader  01 00 
		$a_80_1 = {50 75 70 79 50 61 63 6b 61 67 65 46 69 6e 64 65 72 } //PupyPackageFinder  01 00 
		$a_80_2 = {72 65 67 69 73 74 65 72 5f 70 75 70 79 69 6d 70 6f 72 74 65 72 } //register_pupyimporter  01 00 
		$a_80_3 = {70 75 70 79 5f 61 64 64 5f 70 61 63 6b 61 67 65 } //pupy_add_package  01 00 
		$a_80_4 = {6e 65 74 77 6f 72 6b 2e 6c 69 62 2e 73 74 72 65 61 6d 73 2e 50 75 70 79 53 6f 63 6b 65 74 53 74 72 65 61 6d } //network.lib.streams.PupySocketStream  01 00 
		$a_80_5 = {70 75 70 79 5f 63 72 65 64 65 6e 74 69 61 6c 73 } //pupy_credentials  01 00 
		$a_80_6 = {70 75 70 79 2e 6d 65 6d 69 6d 70 6f 72 74 65 72 2e 63 74 79 70 65 73 } //pupy.memimporter.ctypes  01 00 
		$a_80_7 = {70 75 70 79 2e 6d 61 6e 61 67 65 72 } //pupy.manager  00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Patpoopy_A__2{
	meta:
		description = "VirTool:Win32/Patpoopy.A!!Patpoopy.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {5f 5f 70 75 70 79 69 6d 70 6f 72 74 65 72 5f 64 6c 6c 73 28 } //01 00  __pupyimporter_dlls(
		$a_01_1 = {70 75 70 79 3a 2f 2f 28 } //01 00  pupy://(
		$a_01_2 = {70 75 70 79 69 7a 65 64 3a 20 7b 7d 52 65 } //01 00  pupyized: {}Re
		$a_01_3 = {50 75 70 79 20 63 6f 6e 6e 65 63 74 65 64 3a } //01 00  Pupy connected:
		$a_03_4 = {70 75 70 79 5f 63 72 65 64 65 6e 74 69 61 6c 73 2e 70 79 65 90 02 10 5c 78 30 30 5c 78 30 30 5c 78 30 30 5c 78 30 30 90 00 } //01 00 
		$a_01_5 = {67 69 74 68 75 62 2e 63 6f 6d 2f 6e 31 6e 6a 34 73 65 63 2f 70 75 70 79 } //01 00  github.com/n1nj4sec/pupy
		$a_01_6 = {70 75 70 79 2d 63 6c 69 65 6e 74 2d 7b 7d 2d 7b 7d 2d 64 65 62 75 67 2e 6c 6f 67 } //01 00  pupy-client-{}-{}-debug.log
		$a_01_7 = {6e 65 74 77 6f 72 6b 2e 6c 69 62 2e 73 74 72 65 61 6d 73 2e 50 75 70 79 53 6f 63 6b 65 74 53 74 72 65 61 6d } //00 00  network.lib.streams.PupySocketStream
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Patpoopy_A__3{
	meta:
		description = "VirTool:Win32/Patpoopy.A!!Patpoopy.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,0a 00 0a 00 0d 00 00 01 00 "
		
	strings :
		$a_80_0 = {73 65 6c 66 2e 67 65 74 54 61 73 6b 69 6e 67 73 28 } //self.getTaskings(  01 00 
		$a_80_1 = {73 65 6c 66 2e 70 72 6f 63 65 73 73 54 61 73 6b 69 6e 67 73 28 } //self.processTaskings(  01 00 
		$a_80_2 = {73 65 6c 66 2e 70 6f 73 74 52 65 73 70 6f 6e 73 65 73 28 } //self.postResponses(  01 00 
		$a_80_3 = {73 65 6c 66 2e 61 67 65 6e 74 5f 63 6f 6e 66 69 67 } //self.agent_config  01 00 
		$a_80_4 = {22 4a 69 74 74 65 72 22 3a } //"Jitter":  01 00 
		$a_80_5 = {22 50 61 79 6c 6f 61 64 55 55 49 44 22 3a } //"PayloadUUID":  01 00 
		$a_80_6 = {74 61 73 6b 5b 22 74 61 73 6b 5f 69 64 22 5d } //task["task_id"]  01 00 
		$a_80_7 = {66 69 6c 65 5f 62 72 6f 77 73 65 72 5b 22 66 69 6c 65 73 22 5d } //file_browser["files"]  01 00 
		$a_80_8 = {73 65 6c 66 2e 70 6f 73 74 4d 65 73 73 61 67 65 41 6e 64 52 65 74 72 69 65 76 65 52 65 73 70 6f 6e 73 65 28 } //self.postMessageAndRetrieveResponse(  01 00 
		$a_80_9 = {2e 43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 28 } //.CreateRemoteThread(  01 00 
		$a_80_10 = {70 61 73 73 65 64 4b 69 6c 6c 64 61 74 65 28 } //passedKilldate(  01 00 
		$a_80_11 = {22 50 72 6f 78 79 48 6f 73 74 22 3a } //"ProxyHost":  01 00 
		$a_80_12 = {73 65 6c 66 2e 61 67 65 6e 74 53 6c 65 65 70 28 29 } //self.agentSleep()  00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Patpoopy_A__4{
	meta:
		description = "VirTool:Win32/Patpoopy.A!!Patpoopy.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,06 00 06 00 11 00 00 01 00 "
		
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