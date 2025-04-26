
rule Trojan_Win32_Koobface_gen_D{
	meta:
		description = "Trojan:Win32/Koobface.gen!D,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {47 45 54 20 2f 76 78 2f 3f 75 70 74 69 6d 65 3d 25 6c 64 26 76 3d 25 64 26 73 75 62 3d 25 64 26 70 69 6e 67 3d 25 6c 64 20 48 54 54 50 2f 31 2e 30 } //1 GET /vx/?uptime=%ld&v=%d&sub=%d&ping=%ld HTTP/1.0
		$a_01_1 = {6e 65 74 73 68 20 66 69 72 65 77 61 6c 6c 20 61 64 64 20 70 6f 72 74 6f 70 65 6e 69 6e 67 20 54 43 50 20 38 30 20 25 73 20 45 4e 41 42 4c 45 } //1 netsh firewall add portopening TCP 80 %s ENABLE
		$a_01_2 = {6e 65 74 73 68 20 61 64 64 20 61 6c 6c 6f 77 65 64 70 72 6f 67 72 61 6d 20 22 25 73 22 20 25 73 20 45 4e 41 42 4c 45 } //1 netsh add allowedprogram "%s" %s ENABLE
		$a_01_3 = {3c 21 2d 2d 20 4c 41 42 45 4c 5f 43 4f 44 45 43 20 2d 2d 3e } //1 <!-- LABEL_CODEC -->
		$a_01_4 = {5c 77 65 62 73 72 76 78 5c 77 65 62 73 72 76 78 2e 64 61 74 } //1 \websrvx\websrvx.dat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}