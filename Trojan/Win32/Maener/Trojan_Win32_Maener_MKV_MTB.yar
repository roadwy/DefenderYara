
rule Trojan_Win32_Maener_MKV_MTB{
	meta:
		description = "Trojan:Win32/Maener.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c1 33 d2 f7 75 ec 41 8a 82 ?? ?? ?? ?? 30 44 31 ff 3b cf 72 ea 83 ec 0c 8d 8d 88 fe ff ff 53 e8 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}