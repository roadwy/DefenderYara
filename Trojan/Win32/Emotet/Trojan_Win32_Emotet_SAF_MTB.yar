
rule Trojan_Win32_Emotet_SAF_MTB{
	meta:
		description = "Trojan:Win32/Emotet.SAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 f9 81 e1 90 01 04 8b 7d 90 01 01 8b 75 90 01 01 8a 1c 37 8b 75 90 01 01 32 1c 0e 8b 4d 90 01 01 8b 75 90 01 01 88 1c 31 81 c6 90 01 04 8b 4d 90 01 01 39 ce 8b 4d 90 01 01 89 75 90 01 01 89 4d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}