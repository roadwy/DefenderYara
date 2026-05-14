
rule Trojan_Win32_Tedy_AHA_MTB{
	meta:
		description = "Trojan:Win32/Tedy.AHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 04 00 00 "
		
	strings :
		$a_01_0 = {5b 2a 5d 20 53 74 61 72 74 69 6e 67 20 65 6e 63 72 79 70 74 65 64 20 64 6f 77 6e 6c 6f 61 64 20 6c 6f 61 64 65 72 } //10 [*] Starting encrypted download loader
		$a_01_1 = {5b 2b 5d 20 44 6f 77 6e 6c 6f 61 64 65 64 20 61 6e 64 20 65 6e 63 72 79 70 74 65 64 20 25 64 20 62 79 74 65 73 } //20 [+] Downloaded and encrypted %d bytes
		$a_01_2 = {46 61 69 6c 65 64 20 74 6f 20 72 65 73 74 61 72 74 20 61 73 20 61 64 6d 69 6e 3a 20 25 64 } //30 Failed to restart as admin: %d
		$a_01_3 = {69 66 20 28 2d 6e 6f 74 20 28 54 65 73 74 2d 50 61 74 68 20 24 72 65 67 50 61 74 68 29 29 20 7b 20 4e 65 77 2d 49 74 65 6d 20 2d 50 61 74 68 20 24 72 65 67 50 61 74 68 20 2d 46 6f 72 63 65 20 7d } //40 if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force }
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*20+(#a_01_2  & 1)*30+(#a_01_3  & 1)*40) >=100
 
}