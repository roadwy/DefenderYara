
rule Trojan_BAT_WarzoneRat_DA_MTB{
	meta:
		description = "Trojan:BAT/WarzoneRat.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {24 62 35 38 37 61 61 64 32 2d 31 65 61 34 2d 34 31 36 66 2d 39 39 30 34 2d 62 64 38 64 34 61 66 33 61 30 37 32 } //1 $b587aad2-1ea4-416f-9904-bd8d4af3a072
		$a_81_1 = {54 61 6e 6b 47 61 6d 65 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //1 TankGame.My.Resources
		$a_81_2 = {54 61 6e 6b 47 61 6d 65 2e 52 65 73 6f 75 72 63 65 73 } //1 TankGame.Resources
		$a_81_3 = {72 65 73 6f 75 72 63 65 73 5c 49 6d 61 67 65 73 5c 74 75 74 2e 70 6e 67 } //1 resources\Images\tut.png
		$a_81_4 = {72 65 73 6f 75 72 63 65 73 5c 49 6d 61 67 65 73 5c 74 61 6e 6b 2e 70 6e 67 } //1 resources\Images\tank.png
		$a_81_5 = {4e 6f 62 6f 64 79 20 68 61 73 20 77 6f 6e 21 } //1 Nobody has won!
		$a_81_6 = {4a 61 76 61 6e 65 73 65 20 54 65 78 74 } //1 Javanese Text
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}