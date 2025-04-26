
rule PWS_Win32_OnLineGames_EY{
	meta:
		description = "PWS:Win32/OnLineGames.EY,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0c 00 04 00 00 "
		
	strings :
		$a_02_0 = {59 8d bd b8 f0 ff ff f3 a5 66 a5 b9 c9 03 00 00 33 c0 8d bd ce f0 ff ff 68 ?? ?? ?? ?? f3 ab 66 ab 8d 85 b8 f0 ff ff 68 ?? ?? ?? ?? 50 e8 } //10
		$a_00_1 = {68 74 74 70 3a 2f 2f 24 31 25 73 24 31 3a 25 64 25 73 3f 25 73 } //1 http://$1%s$1:%d%s?%s
		$a_00_2 = {25 73 24 31 25 73 24 31 2a 24 31 2e 64 6c 6c } //1 %s$1%s$1*$1.dll
		$a_00_3 = {64 72 69 24 31 76 65 72 73 5c 65 24 31 74 63 5c 68 6f 73 24 31 74 73 } //1 dri$1vers\e$1tc\hos$1ts
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=12
 
}