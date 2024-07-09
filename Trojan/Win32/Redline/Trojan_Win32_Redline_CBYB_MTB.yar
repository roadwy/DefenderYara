
rule Trojan_Win32_Redline_CBYB_MTB{
	meta:
		description = "Trojan:Win32/Redline.CBYB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 75 10 8a 82 ?? ?? ?? ?? 32 c3 8b 55 08 0f b6 1c 16 8d 0c 18 88 0c 16 fe c9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}