
rule Trojan_Win32_Ekstak_RW_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 ec 0c 53 56 57 68 51 5c 4c 00 e8 fd ec f5 ff 83 c4 04 e9 } //5
		$a_01_1 = {55 8b ec 83 ec 0c 53 56 57 e8 62 ec f5 ff 89 45 fc e9 } //5
		$a_01_2 = {55 8b ec 83 ec 0c 53 56 57 e8 22 ed f5 ff 0f be c0 89 45 fc e9 } //5
		$a_01_3 = {40 00 00 40 5f 66 6c 61 63 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*1) >=6
 
}