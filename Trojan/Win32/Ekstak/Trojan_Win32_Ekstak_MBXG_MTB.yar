
rule Trojan_Win32_Ekstak_MBXG_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.MBXG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 6a ff 68 ?? 87 65 00 68 ?? 76 65 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 68 53 56 57 89 65 e8 33 db 89 5d fc 6a 02 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}