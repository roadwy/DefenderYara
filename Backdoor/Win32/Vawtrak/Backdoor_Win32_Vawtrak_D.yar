
rule Backdoor_Win32_Vawtrak_D{
	meta:
		description = "Backdoor:Win32/Vawtrak.D,SIGNATURE_TYPE_PEHSTR_EXT,05 00 02 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 76 61 6c 28 66 75 6e 63 74 69 6f 6e 28 70 2c 61 2c 63 2c 6b 2c 65 2c 72 29 7b } //01 00  eval(function(p,a,c,k,e,r){
		$a_01_1 = {25 73 2e 70 66 78 } //01 00  %s.pfx
		$a_01_2 = {26 69 6e 66 6f 3d 25 30 2e 32 58 25 30 2e 32 58 25 30 2e 32 58 25 30 2e 32 58 25 30 2e 32 58 25 30 2e 32 58 25 30 2e 32 58 25 30 2e 34 58 25 30 2e 32 58 25 30 2e 34 58 26 70 72 6f 78 79 3d 25 73 } //01 00  &info=%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.4X%0.2X%0.4X&proxy=%s
		$a_01_3 = {2e 2f 2e 2f 40 4c 6f 6e 67 4c 69 6e 6b } //01 00  ././@LongLink
		$a_01_4 = {2f 70 6f 73 74 2e 61 73 70 78 3f 6d 65 73 73 61 67 65 49 44 3d 25 75 } //00 00  /post.aspx?messageID=%u
		$a_00_5 = {80 10 } //00 00 
	condition:
		any of ($a_*)
 
}