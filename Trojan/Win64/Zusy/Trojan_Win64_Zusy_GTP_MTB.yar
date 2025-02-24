
rule Trojan_Win64_Zusy_GTP_MTB{
	meta:
		description = "Trojan:Win64/Zusy.GTP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_80_0 = {64 69 73 63 6f 72 64 2e 67 67 } //discord.gg  1
		$a_01_1 = {53 70 6f 74 69 66 79 20 52 65 63 6f 69 6c 20 4d 61 63 72 6f } //1 Spotify Recoil Macro
		$a_01_2 = {64 00 69 00 73 00 63 00 6f 00 72 00 64 00 2e 00 63 00 6f 00 6d 00 2f 00 75 00 73 00 65 00 72 00 73 00 2f 00 39 00 39 00 33 00 39 00 37 00 36 00 35 00 30 00 35 00 36 00 32 00 37 00 35 00 38 00 36 00 35 00 39 00 31 00 73 00 73 00 73 00 73 00 73 00 73 00 73 00 73 00 73 00 } //2 discord.com/users/993976505627586591sssssssss
	condition:
		((#a_80_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=4
 
}