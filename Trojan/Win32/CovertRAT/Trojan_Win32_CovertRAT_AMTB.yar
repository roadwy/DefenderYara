
rule Trojan_Win32_CovertRAT_AMTB{
	meta:
		description = "Trojan:Win32/CovertRAT!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_80_0 = {5f 5f 50 45 52 53 49 53 54 5f 5f 3a 5f 5f 50 45 52 53 49 53 54 5f 52 45 4d 4f 56 45 5f 5f 5f 5f 42 45 41 43 4f 4e 5f 5f 3a 5f 5f 44 4f 57 4e 4c 4f 41 44 5f 5f 3a 5f 5f 55 50 4c 4f 41 44 5f 5f 7c 5f 5f 48 41 52 56 45 53 54 5f 5f 5f 5f 45 4e 43 52 59 50 54 5f 5f 3a 5f 5f 44 45 43 52 59 50 54 5f 5f 3a 5f 5f 45 4c 45 56 41 54 45 5f 5f } //__PERSIST__:__PERSIST_REMOVE____BEACON__:__DOWNLOAD__:__UPLOAD__|__HARVEST____ENCRYPT__:__DECRYPT__:__ELEVATE__  2
		$a_80_1 = {73 74 65 61 6c 65 72 2e 90 01 03 5f 5f 45 52 52 4f 52 5f 5f 3a 73 74 65 61 6c 65 72 2e 90 01 03 20 6e 6f 20 65 6e 63 6f 6e 74 72 61 64 6f 2e 20 45 6c 20 73 65 72 76 69 64 6f 72 20 64 65 62 65 20 73 75 62 69 72 6c 6f 20 70 72 69 6d 65 72 6f 2e } //stealer.�__ERROR__:stealer.� no encontrado. El servidor debe subirlo primero.  2
		$a_80_2 = {72 61 6e 73 6f 6d 77 61 72 65 2e 90 01 03 5f 5f 45 52 52 4f 52 5f 5f 3a 72 61 6e 73 6f 6d 77 61 72 65 2e 90 01 03 20 6e 6f 20 65 6e 63 6f 6e 74 72 61 64 6f 2e 20 45 6c 20 73 65 72 76 69 64 6f 72 20 64 65 62 65 20 73 75 62 69 72 6c 6f 20 70 72 69 6d 65 72 6f 2e } //ransomware.�__ERROR__:ransomware.� no encontrado. El servidor debe subirlo primero.  2
		$a_80_3 = {73 74 65 61 6c 5f 63 72 65 64 65 6e 74 69 61 6c 73 } //steal_credentials  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*1) >=7
 
}