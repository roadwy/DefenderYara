
rule Trojan_Win64_SalatStealer_ABST_MTB{
	meta:
		description = "Trojan:Win64/SalatStealer.ABST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 ff c5 45 32 14 08 41 8d 40 01 44 8d 0c b5 ?? ?? ?? ?? ff c6 45 88 14 09 44 32 1c 08 41 8d 41 01 44 88 1c 08 41 8d 40 02 32 1c 08 41 8d 41 02 88 1c 08 41 8d 40 03 40 32 3c 08 41 8d 41 03 40 88 3c 08 83 fe } //3
		$a_01_1 = {63 6d 64 2e 65 78 65 20 2f 63 20 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 4e 6f 50 72 6f 66 69 6c 65 20 2d 4e 6f 6e 49 6e 74 65 72 61 63 74 69 76 65 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 2d 43 6f 6d 6d 61 6e 64 20 22 41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 61 74 68 20 27 25 73 27 20 2d 46 6f 72 63 65 20 2d 45 72 72 6f 72 41 63 74 69 6f 6e 20 53 69 6c 65 6e 74 6c 79 43 6f 6e 74 69 6e 75 65 } //2 cmd.exe /c powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -Command "Add-MpPreference -ExclusionPath '%s' -Force -ErrorAction SilentlyContinue
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}