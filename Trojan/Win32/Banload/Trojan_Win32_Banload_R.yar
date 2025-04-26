
rule Trojan_Win32_Banload_R{
	meta:
		description = "Trojan:Win32/Banload.R,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 79 70 65 2e 2e 68 61 73 68 2e 73 74 72 75 63 74 20 7b 20 46 20 75 69 6e 74 70 74 72 3b 20 6f 73 2f 65 78 65 63 2e 77 20 69 6f 2e 57 72 69 74 65 72 3b 20 6f 73 2f 65 78 65 63 2e 70 72 20 2a 6f 73 2e 46 69 6c 65 20 7d } //1 type..hash.struct { F uintptr; os/exec.w io.Writer; os/exec.pr *os.File }
		$a_01_1 = {6b 65 79 70 61 6e 69 63 3a 20 72 65 66 65 72 65 72 72 65 66 72 65 73 68 72 75 6e 6e 69 6e 67 73 65 72 69 61 6c 3a 73 69 67 6e 61 6c } //1 keypanic: refererrefreshrunningserial:signal
		$a_01_2 = {22 2a 63 68 61 63 68 61 32 30 70 6f 6c 79 31 33 30 35 2e 63 68 61 63 68 61 32 30 70 6f 6c 79 31 33 30 35 } //1 "*chacha20poly1305.chacha20poly1305
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}