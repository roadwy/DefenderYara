
rule Trojan_Win64_VibrantPony_B{
	meta:
		description = "Trojan:Win64/VibrantPony.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 64 00 c7 45 ?? ?? 00 6c 00 } //1
		$a_01_1 = {ba 0c 09 3d 00 41 8b } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}