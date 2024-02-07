
rule Trojan_Win32_Pyderwdx_dha{
	meta:
		description = "Trojan:Win32/Pyderwdx!dha,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 25 00 77 00 73 00 } //01 00  cmd.exe /c %ws
		$a_01_1 = {69 66 20 65 78 69 73 74 20 25 25 31 20 64 65 6c 20 25 25 31 20 65 6c 73 65 20 67 6f 74 6f 20 45 78 69 74 } //01 00  if exist %%1 del %%1 else goto Exit
		$a_01_2 = {57 72 69 74 65 46 61 6b 65 72 53 76 63 68 6f 73 74 28 29 20 65 6e 64 } //01 00  WriteFakerSvchost() end
		$a_01_3 = {50 79 49 6e 6a 65 63 74 20 61 20 70 72 6f 63 65 73 73 3a 20 5b 25 77 73 5d 5b 25 6c 64 5d } //01 00  PyInject a process: [%ws][%ld]
		$a_01_4 = {4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 57 69 6e 64 6f 77 73 3b 20 55 3b 20 4d 53 49 45 20 39 2e 30 3b 20 57 49 6e 64 6f 77 73 20 4e 54 20 39 2e 30 3b 20 65 6e 2d 55 53 29 29 } //00 00  Mozilla/5.0 (Windows; U; MSIE 9.0; WIndows NT 9.0; en-US))
	condition:
		any of ($a_*)
 
}