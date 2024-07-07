
rule Backdoor_Linux_Gafgyt_G_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.G!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {77 67 65 74 20 68 74 74 70 3a 2f 2f 62 61 64 6c 75 63 6b 6a 6f 73 68 2e 70 77 2f 64 6f 6e 67 73 2f 62 6c 6a 2e 73 68 20 7c 7c } //1 wget http://badluckjosh.pw/dongs/blj.sh ||
		$a_00_1 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 3b 65 63 68 6f 20 2d 65 20 27 5c 31 34 37 5c 31 34 31 5c 31 37 31 5c 31 34 36 5c 31 34 37 5c 31 36 34 } //1 /bin/busybox;echo -e '\147\141\171\146\147\164
		$a_00_2 = {73 65 6e 64 48 4f 4c 44 } //1 sendHOLD
		$a_00_3 = {73 65 6e 64 4a 55 4e 4b } //1 sendJUNK
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}
rule Backdoor_Linux_Gafgyt_G_xp_2{
	meta:
		description = "Backdoor:Linux/Gafgyt.G!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {71 43 38 63 56 75 47 54 6e 52 48 36 63 66 76 37 73 6a 63 59 50 46 76 37 67 75 41 6d 5a 78 62 51 52 63 35 37 66 56 37 37 49 55 55 6a 35 62 36 77 6f 63 70 66 46 4a 50 6d 48 43 } //1 qC8cVuGTnRH6cfv7sjcYPFv7guAmZxbQRc57fV77IUUj5b6wocpfFJPmHC
		$a_00_1 = {6e 70 78 58 6f 75 64 69 66 46 65 45 67 47 61 41 43 53 63 73 } //1 npxXoudifFeEgGaACScs
		$a_00_2 = {6c 58 66 59 43 37 54 46 61 43 71 35 48 76 39 38 32 77 75 49 69 4b 63 48 6c 67 46 41 30 6a 45 73 57 32 4f 46 51 53 74 4f 37 78 36 7a 4e 39 64 42 67 61 79 79 57 67 76 62 6b 30 4c 33 6c 5a 43 6c 7a 4a 43 6d 46 47 33 47 56 4e 44 46 63 32 69 54 48 4e 59 79 37 67 73 73 38 64 48 62 6f 42 64 65 4b 45 31 56 63 62 6c 48 31 41 78 72 56 79 69 71 6f 6b 77 32 52 59 46 76 64 34 63 64 31 51 78 79 61 48 61 77 77 50 36 67 6f 39 } //1 lXfYC7TFaCq5Hv982wuIiKcHlgFA0jEsW2OFQStO7x6zN9dBgayyWgvbk0L3lZClzJCmFG3GVNDFc2iTHNYy7gss8dHboBdeKE1VcblH1AxrVyiqokw2RYFvd4cd1QxyaHawwP6go9
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}