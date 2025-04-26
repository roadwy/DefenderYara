
rule Trojan_Win32_Babar_OKV_MTB{
	meta:
		description = "Trojan:Win32/Babar.OKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 db 03 fb 81 e7 ff 00 00 80 79 ?? 4f 81 cf 00 ff ff ff 47 0f b6 5c 37 02 8b 7d e8 30 1c 07 8a 1c 07 a8 0f 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}