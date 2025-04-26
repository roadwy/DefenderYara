
rule Trojan_Win64_VibrantPony_C{
	meta:
		description = "Trojan:Win64/VibrantPony.C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {88 01 03 c6 48 03 ce 83 f8 6a 72 } //1
		$a_03_1 = {41 8b c5 48 8d ?? ?? 88 01 03 c6 48 03 ce 83 f8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}