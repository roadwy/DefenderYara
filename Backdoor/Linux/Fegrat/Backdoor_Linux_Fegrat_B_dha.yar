
rule Backdoor_Linux_Fegrat_B_dha{
	meta:
		description = "Backdoor:Linux/Fegrat.B!dha,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {52 65 64 46 6c 61 72 65 2f 72 61 74 2f 6d 6f 64 75 6c 65 73 2f 73 6f 63 6b 73 2e 28 2a 48 54 54 50 50 72 6f 78 79 43 6c 69 65 6e 74 29 2e 68 61 6e 64 73 68 61 6b 65 } //1 RedFlare/rat/modules/socks.(*HTTPProxyClient).handshake
		$a_00_1 = {52 65 64 46 6c 61 72 65 2f 72 61 74 2f 70 6c 61 74 66 6f 72 6d 73 2f 6c 69 6e 75 78 2f 64 79 6c 6f 61 64 65 72 2e 28 2a 6d 65 6d 6f 72 79 4c 6f 61 64 65 72 29 2e 45 78 65 63 75 74 65 50 6c 75 67 69 6e 46 75 6e 63 74 69 6f 6e 2e 66 75 6e 63 31 2e 31 } //1 RedFlare/rat/platforms/linux/dyloader.(*memoryLoader).ExecutePluginFunction.func1.1
		$a_00_2 = {52 65 64 46 6c 61 72 65 2f 72 61 74 2e 43 6f 72 65 2e 44 65 73 74 72 6f 79 } //1 RedFlare/rat.Core.Destroy
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}