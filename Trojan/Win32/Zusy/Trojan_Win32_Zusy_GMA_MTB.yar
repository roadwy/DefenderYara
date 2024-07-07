
rule Trojan_Win32_Zusy_GMA_MTB{
	meta:
		description = "Trojan:Win32/Zusy.GMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {36 82 4d 00 a3 90 01 04 c7 05 90 01 04 9c 82 4d 00 c7 05 90 01 04 dc 81 4d 00 c7 05 90 01 04 84 82 4d 00 a3 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}