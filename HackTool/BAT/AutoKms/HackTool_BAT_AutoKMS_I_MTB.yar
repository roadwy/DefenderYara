
rule HackTool_BAT_AutoKMS_I_MTB{
	meta:
		description = "HackTool:BAT/AutoKMS.I!MTB,SIGNATURE_TYPE_PEHSTR,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 54 75 6e 4d 69 72 72 6f 72 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 54 75 6e 4d 69 72 72 6f 72 2e 70 64 62 } //10 \TunMirror\obj\Release\TunMirror.pdb
		$a_01_1 = {24 36 61 31 66 34 30 31 36 2d 66 31 36 65 2d 34 31 62 63 2d 38 30 66 62 2d 30 36 34 32 63 38 61 33 34 38 39 33 } //1 $6a1f4016-f16e-41bc-80fb-0642c8a34893
		$a_01_2 = {24 37 30 66 31 37 61 34 65 2d 63 63 38 63 2d 34 34 61 37 2d 39 39 63 32 2d 65 33 61 30 65 32 35 35 34 37 35 38 } //1 $70f17a4e-cc8c-44a7-99c2-e3a0e2554758
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=11
 
}