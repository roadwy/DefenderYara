
rule HackTool_MacOS_SuspBinary_P{
	meta:
		description = "HackTool:MacOS/SuspBinary.P,SIGNATURE_TYPE_MACHOHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_00_0 = {43 79 6d 75 6c 61 74 65 52 65 76 65 72 73 65 53 68 65 6c 6c 2e 64 6c 6c } //5 CymulateReverseShell.dll
		$a_00_1 = {43 79 6d 75 6c 61 74 65 43 6f 69 6e 4d 69 6e 65 72 43 6f 72 65 2e 64 6c 6c } //5 CymulateCoinMinerCore.dll
		$a_00_2 = {43 52 59 50 54 4f 5f 61 64 64 5f 6c 6f 63 6b 5f 70 74 72 } //1 CRYPTO_add_lock_ptr
		$a_00_3 = {69 73 5f 65 78 65 5f 65 6e 61 62 6c 65 64 5f 66 6f 72 5f 65 78 65 63 75 74 69 6f 6e } //1 is_exe_enabled_for_execution
		$a_00_4 = {43 61 6c 6c 65 72 20 69 73 20 52 65 76 65 72 73 65 20 50 2f 49 6e 76 6f 6b 65 } //1 Caller is Reverse P/Invoke
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*5+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=6
 
}