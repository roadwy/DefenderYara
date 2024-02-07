
rule TrojanSpy_Win32_Bancos_gen_L{
	meta:
		description = "TrojanSpy:Win32/Bancos.gen!L,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 0c 00 00 01 00 "
		
	strings :
		$a_01_0 = {2a 75 40 70 2e 23 65 23 78 65 40 } //01 00  *u@p.#e#xe@
		$a_01_1 = {76 23 65 72 23 73 40 61 23 6f 2e 40 64 23 6c 2a 6c 23 } //01 00  v#er#s@a#o.@d#l*l#
		$a_01_2 = {42 61 23 6e 63 6f 20 53 61 6e 74 23 61 6e 64 65 72 20 42 72 61 23 73 69 6c } //01 00  Ba#nco Sant#ander Bra#sil
		$a_01_3 = {53 65 23 6e 68 61 20 64 6f 20 63 61 23 72 74 } //01 00  Se#nha do ca#rt
		$a_01_4 = {23 75 23 70 40 2e 40 65 23 78 2a 65 } //01 00  #u#p@.@e#x*e
		$a_01_5 = {76 40 65 2a 72 23 73 61 40 6f 23 2e 40 64 6c 2a 6c 2a } //01 00  v@e*r#sa@o#.@dl*l*
		$a_01_6 = {54 23 65 6e 74 23 65 20 6e 6f 76 23 61 6d 65 23 6e 74 65 } //01 00  T#ent#e nov#ame#nte
		$a_01_7 = {53 65 23 6e 68 61 20 64 23 6f 20 54 6f 6b 23 65 6e 20 69 6e 76 23 } //01 00  Se#nha d#o Tok#en inv#
		$a_01_8 = {40 75 2a 70 2e 2a 65 40 78 2a 65 23 } //01 00  @u*p.*e@x*e#
		$a_01_9 = {76 65 2a 72 2a 73 61 6f 2a 2e 23 64 23 6c 2a 6c } //01 00  ve*r*sao*.#d#l*l
		$a_01_10 = {42 72 61 23 64 65 73 23 63 6f } //01 00  Bra#des#co
		$a_01_11 = {78 2a 72 23 2f 40 74 23 65 40 6e 23 2e 2a 32 2a 70 40 75 23 70 2a 72 2a 6f 23 63 2a 73 } //00 00  x*r#/@t#e@n#.*2*p@u#p*r*o#c*s
	condition:
		any of ($a_*)
 
}