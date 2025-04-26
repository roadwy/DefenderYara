
rule Trojan_Win32_Redline_GKX_MTB{
	meta:
		description = "Trojan:Win32/Redline.GKX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 08 0f be 04 0a 8b 4d 0c 03 4d d0 0f be 11 33 c2 88 45 ce 8b 45 0c 03 45 d0 8a 08 88 4d cf 0f be 55 ce 0f be 45 cf 03 d0 8b 4d 0c 03 4d d0 88 11 0f be 55 cf 8b 45 0c 03 45 d0 0f be 08 2b ca 8b 55 0c 03 55 d0 88 0a } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}