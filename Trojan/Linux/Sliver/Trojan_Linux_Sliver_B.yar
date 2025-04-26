
rule Trojan_Linux_Sliver_B{
	meta:
		description = "Trojan:Linux/Sliver.B,SIGNATURE_TYPE_ELFHSTR_EXT,07 00 07 00 09 00 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 } //2 DllUnregisterServer
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_01_2 = {44 6c 6c 49 6e 73 74 61 6c 6c } //1 DllInstall
		$a_01_3 = {47 65 74 4a 69 74 74 65 72 } //1 GetJitter
		$a_01_4 = {56 6f 69 64 46 75 6e 63 } //2 VoidFunc
		$a_01_5 = {47 65 74 4b 69 6c 6c } //2 GetKill
		$a_01_6 = {41 64 64 54 75 6e 6e 65 6c } //2 AddTunnel
		$a_01_7 = {47 65 74 49 73 49 4f 43 } //1 GetIsIOC
		$a_01_8 = {47 6f 20 62 75 69 6c 64 69 6e 66 3a } //1 Go buildinf:
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=7
 
}