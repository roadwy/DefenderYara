
rule Trojan_BAT_Disstl_A_MTB{
	meta:
		description = "Trojan:BAT/Disstl.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 0a 00 00 "
		
	strings :
		$a_80_0 = {2f 73 20 2f 74 20 7b 30 7d } ///s /t {0}  3
		$a_80_1 = {5c 50 72 6f 67 72 61 6d 73 5c 44 69 73 63 6f 72 64 } //\Programs\Discord  3
		$a_80_2 = {5c 74 6f 6b 65 6e 73 2e 74 78 74 } //\tokens.txt  3
		$a_80_3 = {4c 6f 63 61 6c 20 53 74 6f 72 61 67 65 5c 6c 65 76 65 6c 64 62 } //Local Storage\leveldb  3
		$a_80_4 = {44 69 73 63 6f 72 64 47 72 61 62 62 65 72 } //DiscordGrabber  3
		$a_80_5 = {4d 69 6e 65 63 72 61 66 74 53 74 65 61 6c 65 72 } //MinecraftStealer  3
		$a_80_6 = {48 61 73 4d 69 6e 65 63 72 61 66 74 49 6e 73 74 61 6c 6c 65 64 } //HasMinecraftInstalled  3
		$a_80_7 = {63 6f 6e 6e 65 63 74 69 6f 6e 5f 74 72 61 63 65 2e 74 78 74 } //connection_trace.txt  3
		$a_80_8 = {46 69 6e 64 54 6f 6b 65 6e 73 46 6f 72 50 61 74 68 } //FindTokensForPath  3
		$a_80_9 = {4f 70 65 6e 41 6c 67 6f 72 69 74 68 6d 50 72 6f 76 69 64 65 72 } //OpenAlgorithmProvider  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3+(#a_80_7  & 1)*3+(#a_80_8  & 1)*3+(#a_80_9  & 1)*3) >=30
 
}
rule Trojan_BAT_Disstl_A_MTB_2{
	meta:
		description = "Trojan:BAT/Disstl.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 11 00 08 00 00 "
		
	strings :
		$a_80_0 = {63 6f 6e 73 74 20 63 68 69 6c 64 5f 70 72 6f 63 65 73 73 20 3d 20 72 65 71 75 69 72 65 28 27 63 68 69 6c 64 5f 70 72 6f 63 65 73 73 27 29 } //const child_process = require('child_process')  5
		$a_80_1 = {63 68 69 6c 64 5f 70 72 6f 63 65 73 73 2e 65 78 65 63 53 79 6e 63 28 60 7b 30 7d 24 7b 7b 5f 5f 64 69 72 6e 61 6d 65 7d 7d 2f 7b 31 7d 2f 55 70 64 61 74 65 2e 65 78 65 7b 32 7d 60 29 } //child_process.execSync(`{0}${{__dirname}}/{1}/Update.exe{2}`)  5
		$a_80_2 = {72 65 71 75 69 72 65 28 5f 5f 64 69 72 6e 61 6d 65 20 2b 20 27 2f 7b 33 7d 2f 69 6e 6a 65 63 74 2e 6a 73 27 29 } //require(__dirname + '/{3}/inject.js')  5
		$a_80_3 = {6d 66 61 5c 2e 28 5c 77 7c 5c 64 7c 5f 7c 2d 29 7b 38 34 7d } //mfa\.(\w|\d|_|-){84}  4
		$a_80_4 = {28 5c 77 7c 5c 64 29 7b 32 34 7d 5c 2e 28 5c 77 7c 5c 64 7c 5f 7c 2d 29 7b 36 7d 2e 28 5c 77 7c 5c 64 7c 5f 7c 2d 29 7b 32 37 7d } //(\w|\d){24}\.(\w|\d|_|-){6}.(\w|\d|_|-){27}  4
		$a_80_5 = {64 69 73 63 6f 72 64 6d 6f 64 2e 6a 73 } //discordmod.js  3
		$a_80_6 = {70 72 65 6c 6f 61 64 2e 6a 73 } //preload.js  3
		$a_80_7 = {69 6e 6a 65 63 74 2e 6a 73 } //inject.js  3
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*5+(#a_80_2  & 1)*5+(#a_80_3  & 1)*4+(#a_80_4  & 1)*4+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3+(#a_80_7  & 1)*3) >=17
 
}