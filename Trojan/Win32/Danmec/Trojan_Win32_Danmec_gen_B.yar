
rule Trojan_Win32_Danmec_gen_B{
	meta:
		description = "Trojan:Win32/Danmec.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {3c 0d 74 1f 6a 02 59 49 8a d9 d0 e3 85 c9 88 5c 0d fc 75 f3 3c 0a 75 05 88 0c 3e eb 05 34 1b } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}