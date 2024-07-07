
rule Trojan_Win32_Avemariarat_VU_MTB{
	meta:
		description = "Trojan:Win32/Avemariarat.VU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 99 f7 bd 90 01 04 89 95 90 01 04 8b 55 90 01 01 03 55 90 01 01 0f be 02 8b 8d 90 01 04 0f be 54 0d 90 01 01 33 c2 8b 4d 90 01 01 03 4d 90 01 01 88 01 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}