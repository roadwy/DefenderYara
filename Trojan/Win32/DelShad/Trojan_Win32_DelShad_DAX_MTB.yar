
rule Trojan_Win32_DelShad_DAX_MTB{
	meta:
		description = "Trojan:Win32/DelShad.DAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {bc 80 b3 18 e1 5c 80 f9 21 3d fb fc fa a0 68 10 a7 38 08 00 2b 33 71 b5 43 6c 61 73 } //01 00 
		$a_01_1 = {6b 82 4f bd 52 33 63 b2 af 49 91 3a 4f ad 33 99 66 cf 11 b7 } //00 00 
	condition:
		any of ($a_*)
 
}