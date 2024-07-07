
rule HackTool_Win32_KeyGen_A_MTB{
	meta:
		description = "HackTool:Win32/KeyGen.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {8a 06 8a 56 01 8a 5e 02 8a e0 8a f2 8a fb 80 e4 03 80 e6 0f 80 e7 3f c0 e8 02 c0 ea 04 c0 eb 06 c0 e4 04 c0 e6 02 0a e2 0a de 0f b6 d0 0f b6 cc } //1
		$a_81_1 = {2d 70 75 62 6b 65 79 } //1 -pubkey
		$a_81_2 = {2d 70 72 69 76 6b 65 79 } //1 -privkey
		$a_81_3 = {44 45 43 52 59 50 54 49 4f 4e 5f 49 44 2e 74 78 74 } //1 DECRYPTION_ID.txt
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}