
rule TrojanDropper_BAT_Addrop_B_bit{
	meta:
		description = "TrojanDropper:BAT/Addrop.B!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 00 43 00 20 00 6e 00 65 00 74 00 73 00 68 00 20 00 69 00 6e 00 74 00 65 00 72 00 66 00 61 00 63 00 65 00 20 00 69 00 70 00 20 00 73 00 65 00 74 00 20 00 64 00 6e 00 73 00 20 00 6e 00 61 00 6d 00 65 00 3d 00 22 00 } //01 00  /C netsh interface ip set dns name="
		$a_01_1 = {11 5c 00 73 00 76 00 72 00 2e 00 63 00 72 00 74 00 00 37 2f 00 43 00 20 00 63 00 65 00 72 00 74 00 75 00 74 00 69 00 6c 00 20 00 2d 00 61 00 64 00 64 00 73 00 74 00 6f 00 72 00 65 00 20 00 52 00 6f 00 6f 00 74 } //01 00 
		$a_01_2 = {63 3a 5c 55 73 65 72 73 5c 73 6f 63 5c } //00 00  c:\Users\soc\
	condition:
		any of ($a_*)
 
}