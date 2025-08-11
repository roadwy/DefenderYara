
rule Trojan_Win64_Lazy_MBZ_MTB{
	meta:
		description = "Trojan:Win64/Lazy.MBZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {73 63 68 74 61 73 6b 73 2e 65 78 65 20 2f 63 72 65 61 74 65 20 2f 74 6e 20 22 53 79 73 74 65 6d 48 65 6c 70 65 72 54 61 73 6b 22 20 2f 74 72 20 22 25 73 22 20 2f 73 63 20 6f 6e 6c 6f 67 6f 6e 20 2f 72 6c 20 48 49 47 48 45 53 54 20 2f 66 } //2 schtasks.exe /create /tn "SystemHelperTask" /tr "%s" /sc onlogon /rl HIGHEST /f
		$a_01_1 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 4e 6f 50 72 6f 66 69 6c 65 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 45 6e 63 6f 64 65 64 43 6f 6d 6d 61 6e 64 20 25 73 } //1 powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand %s
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}