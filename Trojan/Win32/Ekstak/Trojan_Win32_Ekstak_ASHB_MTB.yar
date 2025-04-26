
rule Trojan_Win32_Ekstak_ASHB_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 81 ec 14 05 00 00 8d 45 ec 56 50 ff 35 ?? ?? a6 00 ff 15 ?? ?? 65 00 83 f8 01 0f 85 } //3
		$a_01_1 = {ff d6 25 00 00 00 80 3d 00 00 00 80 74 06 ff d6 3c 04 77 06 ff 15 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}