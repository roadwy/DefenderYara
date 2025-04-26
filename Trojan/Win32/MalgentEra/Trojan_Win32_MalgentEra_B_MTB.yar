
rule Trojan_Win32_MalgentEra_B_MTB{
	meta:
		description = "Trojan:Win32/MalgentEra.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {ef eb f9 ca 0b 9b fc cb ee eb f9 ca 0b 9b fa cb ed eb f9 ca 0b 9b fd cb fa eb f9 ca 0b 9b 8c be 4e bf 9c ae fe bf 8c ad be bf 9c a0 b9 bf 1c be be bf 9c a0 b9 b0 6c ae ee bf 9c a0 b9 bf bc be ee bf 9c a5 26 } //1
		$a_81_1 = {65 76 61 6c 28 } //1 eval(
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}