
rule Trojan_Win32_SdBot_ARAA_MTB{
	meta:
		description = "Trojan:Win32/SdBot.ARAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 63 72 61 63 6b 6d 61 6e 32 2f 69 72 63 5f 6d 63 67 65 65 2f 72 61 77 2f 6d 61 73 74 65 72 2f 75 70 64 61 74 65 2f 69 72 63 5f 6d 63 67 65 65 2e 65 78 65 } //2 /crackman2/irc_mcgee/raw/master/update/irc_mcgee.exe
		$a_01_1 = {40 21 66 6f 72 63 65 75 70 64 61 74 65 } //2 @!forceupdate
		$a_01_2 = {41 44 67 41 41 41 43 35 6c 61 46 39 6d 63 6d 46 74 5a 51 41 3d } //3 ADgAAAC5laF9mcmFtZQA=
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3) >=7
 
}