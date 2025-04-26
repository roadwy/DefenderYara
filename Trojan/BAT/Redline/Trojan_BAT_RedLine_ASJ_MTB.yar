
rule Trojan_BAT_RedLine_ASJ_MTB{
	meta:
		description = "Trojan:BAT/RedLine.ASJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {69 76 55 6f 50 72 49 52 77 57 71 46 49 4d 78 69 6a 73 55 48 56 46 48 53 43 69 62 6e 2e 64 6c 6c } //1 ivUoPrIRwWqFIMxijsUHVFHSCibn.dll
		$a_01_1 = {49 48 4e 54 56 72 70 72 6f 67 58 45 44 42 48 57 79 42 62 72 68 } //1 IHNTVrprogXEDBHWyBbrh
		$a_01_2 = {71 52 6d 56 51 6e 6f 49 55 50 46 55 59 4d 7a 49 72 4d 79 58 2e 64 6c 6c } //1 qRmVQnoIUPFUYMzIrMyX.dll
		$a_01_3 = {42 56 4f 77 77 62 76 48 43 48 50 74 6f 4d 42 6b 4a 53 76 70 72 63 4f 42 6a 64 59 45 59 } //1 BVOwwbvHCHPtoMBkJSvprcOBjdYEY
		$a_01_4 = {52 43 78 65 75 73 52 7a 7a 6a 46 54 61 61 53 46 49 68 69 79 6d 74 43 67 52 55 73 66 64 2e 64 6c 6c } //1 RCxeusRzzjFTaaSFIhiymtCgRUsfd.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}