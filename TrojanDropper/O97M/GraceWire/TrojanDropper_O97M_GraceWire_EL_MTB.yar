
rule TrojanDropper_O97M_GraceWire_EL_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.EL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {50 52 50 20 3d 20 22 25 22 20 2b 20 46 6f 72 6d 30 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 } //1 PRP = "%" + Form0.TextBox1.Tag
		$a_01_1 = {54 42 54 20 3d 20 54 42 54 20 2b 20 22 22 20 2b 20 22 22 } //1 TBT = TBT + "" + ""
		$a_01_2 = {54 42 54 20 3d 20 54 42 54 20 2b 20 22 25 22 } //1 TBT = TBT + "%"
		$a_01_3 = {54 42 54 20 3d 20 54 53 50 49 50 2e 45 78 70 61 6e 64 45 6e 76 69 72 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 28 54 42 54 29 } //1 TBT = TSPIP.ExpandEnvironmentStrings(TBT)
		$a_01_4 = {73 20 3d 20 63 61 72 2e 43 68 65 63 6b 43 61 72 28 54 53 50 49 50 2c 20 46 6f 72 6d 30 2e 54 65 78 74 42 6f 78 33 2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 20 26 20 22 22 29 } //1 s = car.CheckCar(TSPIP, Form0.TextBox3.ControlTipText & "")
		$a_01_5 = {43 68 44 69 72 20 28 46 6f 72 6d 30 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 20 2b 20 22 22 29 } //1 ChDir (Form0.TextBox1.Tag + "")
		$a_01_6 = {49 66 20 74 6f 6f 6f 6c 73 65 74 43 68 75 6e 6b 49 20 41 6e 64 20 6a 20 3d 20 43 6f 75 6e 74 20 41 6e 64 20 43 20 3c 3e 20 22 22 22 22 20 54 68 65 6e 20 47 65 74 50 2e 61 72 61 6d 20 3d 20 47 65 74 50 2e } //1 If tooolsetChunkI And j = Count And C <> """" Then GetP.aram = GetP.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}