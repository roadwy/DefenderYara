
rule TrojanSpy_AndroidOS_Banker_U_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Banker.U!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 62 69 79 69 74 75 6e 69 78 69 6b 6f 2f 70 6f 70 75 6c 6f 6c 6f } //1 com/biyitunixiko/populolo
		$a_01_1 = {63 32 39 7a 61 56 39 7a 62 33 4e 70 63 32 39 75 58 31 39 66 58 77 3d 3d } //1 c29zaV9zb3Npc29uX19fXw==
		$a_01_2 = {63 6f 6d 2e 70 69 77 69 74 69 73 65 79 69 6e 6f 2e 76 69 74 61 70 65 6b 61 2e 64 69 63 61 7a 65 79 61 76 69 73 6f } //1 com.piwitiseyino.vitapeka.dicazeyaviso
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}