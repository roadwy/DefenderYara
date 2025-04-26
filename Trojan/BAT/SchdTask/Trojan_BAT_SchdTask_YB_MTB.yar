
rule Trojan_BAT_SchdTask_YB_MTB{
	meta:
		description = "Trojan:BAT/SchdTask.YB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 00 6f 00 77 00 65 00 72 00 6b 00 61 00 74 00 7a 00 33 00 32 00 } //1 Powerkatz32
		$a_01_1 = {50 00 6f 00 77 00 65 00 72 00 6b 00 61 00 74 00 7a 00 36 00 34 00 } //1 Powerkatz64
		$a_01_2 = {47 00 65 00 74 00 44 00 61 00 74 00 61 00 3a 00 20 00 6e 00 6f 00 74 00 20 00 66 00 6f 00 75 00 6e 00 64 00 20 00 74 00 61 00 73 00 6b 00 4e 00 61 00 6d 00 65 00 } //2 GetData: not found taskName
		$a_01_3 = {44 00 65 00 6c 00 65 00 74 00 65 00 20 00 45 00 78 00 3a 00 } //2 Delete Ex:
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=5
 
}