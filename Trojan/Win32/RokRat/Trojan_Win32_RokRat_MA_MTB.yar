
rule Trojan_Win32_RokRat_MA_MTB{
	meta:
		description = "Trojan:Win32/RokRat.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 1a 2b f1 d1 fe 33 c9 4e 85 f6 7e ?? 83 c2 02 8a 02 8d 52 02 2a c3 88 04 39 41 3b ce 7c } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}