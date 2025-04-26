
rule Trojan_Win32_Redline_SN_MTB{
	meta:
		description = "Trojan:Win32/Redline.SN!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 8d 64 ff ff ff 88 8d 63 ff ff ff 0f b6 95 63 ff ff ff f7 d2 88 95 63 ff ff ff 0f b6 85 63 ff ff ff f7 d8 88 85 63 ff ff ff 0f b6 8d 63 ff ff ff 2b 8d 64 ff ff ff 88 8d 63 ff ff ff 0f b6 95 63 ff ff ff c1 fa 07 0f b6 85 63 ff ff ff d1 e0 0b d0 88 95 63 ff ff ff 0f b6 8d 63 ff ff ff 33 8d 64 ff ff ff 88 8d 63 ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}