
rule Trojan_BAT_DiscordStealer_SN_MTB{
	meta:
		description = "Trojan:BAT/DiscordStealer.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 1e 00 00 06 13 04 11 04 09 6f 1f 00 00 0a 74 19 00 00 01 7d 0c 00 00 04 03 11 04 fe 06 1f 00 00 06 73 20 00 00 0a 28 02 00 00 2b 2d 1d 03 73 1d 00 00 06 25 11 04 7b 0c 00 00 04 6f 22 00 00 0a 6f 0c 00 00 06 6f 23 00 00 0a 09 6f 24 00 00 0a 2d ad } //4
		$a_01_1 = {5c 73 74 65 61 6c 65 72 5c 44 69 73 63 6f 72 64 54 6f 6b 65 6e 47 72 61 62 62 65 72 5c 44 69 73 63 6f 72 64 54 6f 6b 65 6e 47 72 61 62 62 65 72 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 6e 65 74 38 2e 30 5c 77 69 6e 2d 78 36 34 5c } //2 \stealer\DiscordTokenGrabber\DiscordTokenGrabber\obj\Release\net8.0\win-x64\
		$a_00_2 = {44 00 69 00 73 00 63 00 6f 00 72 00 64 00 54 00 6f 00 6b 00 65 00 6e 00 47 00 72 00 61 00 62 00 62 00 65 00 72 00 2e 00 64 00 6c 00 6c 00 } //1 DiscordTokenGrabber.dll
		$a_00_3 = {6d 00 66 00 61 00 5c 00 2e 00 5b 00 5c 00 77 00 2d 00 5d 00 7b 00 38 00 34 00 7d 00 } //1 mfa\.[\w-]{84}
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=8
 
}