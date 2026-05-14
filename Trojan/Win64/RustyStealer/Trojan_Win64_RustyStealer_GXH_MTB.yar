
rule Trojan_Win64_RustyStealer_GXH_MTB{
	meta:
		description = "Trojan:Win64/RustyStealer.GXH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_03_0 = {40 8a 2c 1f 40 30 f5 48 3b bc 24 ?? ?? ?? ?? ?? ?? 4c 89 e9 e8 ?? ?? ?? ?? 48 8b 84 24 ?? ?? ?? ?? 40 88 2c 38 48 ff c7 48 89 bc 24 ?? ?? ?? ?? 40 0f b6 c6 6b f0 9d 40 80 c6 32 48 83 ff 0f } //10
		$a_80_1 = {43 6c 69 70 62 6f 61 72 64 53 65 72 76 65 72 2e 65 78 65 } //ClipboardServer.exe  1
		$a_01_2 = {41 6d 73 69 53 63 61 6e 42 75 66 66 65 72 } //1 AmsiScanBuffer
		$a_01_3 = {63 6d 64 2e 65 78 65 20 2f 65 3a 4f 4e 20 2f 76 3a 4f 46 46 20 2f 64 20 2f 63 20 22 62 61 74 63 68 20 66 69 6c 65 20 61 72 67 75 6d 65 6e 74 73 20 61 72 65 20 69 6e 76 61 6c 69 64 } //1 cmd.exe /e:ON /v:OFF /d /c "batch file arguments are invalid
		$a_01_4 = {4b 69 6c 6c 54 69 6d 65 72 } //1 KillTimer
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=14
 
}