
rule Trojan_Win32_Strab_SPRJ_MTB{
	meta:
		description = "Trojan:Win32/Strab.SPRJ!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {d1 e8 c1 e1 07 46 0b c8 03 cf 03 d1 0f be 3e 8b c2 85 ff 75 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}