
rule Trojan_Win32_Badur_EDEQ_MTB{
	meta:
		description = "Trojan:Win32/Badur.EDEQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 c0 8b 45 dc 8b 0c 90 33 4d 80 8b 55 c0 8b 85 50 ff ff ff 89 0c 90 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}