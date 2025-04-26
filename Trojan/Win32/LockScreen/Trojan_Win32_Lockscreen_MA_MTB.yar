
rule Trojan_Win32_Lockscreen_MA_MTB{
	meta:
		description = "Trojan:Win32/Lockscreen.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e9 04 0a d1 88 14 24 c7 06 01 00 00 00 8a 50 02 80 fa 3d 74 ?? ff 06 8a 0c bd 70 d4 51 00 c1 e1 04 33 db 8a da 8b 1c 9d 70 d4 51 00 c1 eb 02 0a cb 88 4c 24 01 8a 48 03 80 f9 3d 74 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}