
rule Trojan_Win64_Cerbu_SLWZ_MTB{
	meta:
		description = "Trojan:Win64/Cerbu.SLWZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {2d 2d 77 69 6e 64 6f 77 2d 70 6f 73 69 74 69 6f 6e 3d 30 2c 30 20 2d 2d 6e 6f 2d 73 61 6e 64 62 6f 78 20 2d 2d 61 6c 6c 6f 77 2d 6e 6f 2d 73 61 6e 64 62 6f 78 2d 6a 6f 62 20 2d 2d 64 69 73 61 62 6c 65 2d 67 70 75 } //2 --window-position=0,0 --no-sandbox --allow-no-sandbox-job --disable-gpu
		$a_01_1 = {53 68 65 6c 6c 63 6f 64 65 20 72 75 6e 6e 69 6e 67 20 28 74 69 6d 65 6f 75 74 2c 20 73 74 69 6c 6c 20 61 63 74 69 76 65 29 } //2 Shellcode running (timeout, still active)
		$a_01_2 = {4f 4b 3a 20 53 68 65 6c 6c 63 6f 64 65 20 69 6e 6a 65 63 74 65 64 20 28 43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 29 } //2 OK: Shellcode injected (CreateRemoteThread)
		$a_01_3 = {4f 4b 3a 20 50 45 20 69 6e 6a 65 63 74 65 64 20 61 6e 64 20 65 78 65 63 75 74 65 64 } //2 OK: PE injected and executed
		$a_01_4 = {63 6d 64 2e 65 78 65 20 2f 43 20 22 6e 65 74 73 68 20 61 64 76 66 69 72 65 77 61 6c 6c 20 66 69 72 65 77 61 6c 6c 20 73 65 74 20 72 75 6c 65 20 6e 61 6d 65 3d 22 22 25 73 22 22 20 25 73 22 } //2 cmd.exe /C "netsh advfirewall firewall set rule name=""%s"" %s"
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}