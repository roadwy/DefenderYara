
rule Trojan_BAT_Diztakun_SG_MTB{
	meta:
		description = "Trojan:BAT/Diztakun.SG!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {24 36 38 63 32 36 64 62 39 2d 65 30 32 62 2d 34 65 64 66 2d 39 32 33 39 2d 66 31 65 64 36 30 35 39 36 63 61 37 } //1 $68c26db9-e02b-4edf-9239-f1ed60596ca7
		$a_01_1 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 54 00 61 00 73 00 6b 00 4d 00 67 00 72 00 } //1 DisableTaskMgr
		$a_01_2 = {65 00 78 00 63 00 6c 00 75 00 64 00 65 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 2e 00 65 00 78 00 65 00 } //1 excludedownload.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}