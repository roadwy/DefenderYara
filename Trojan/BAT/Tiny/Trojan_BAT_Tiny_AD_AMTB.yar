
rule Trojan_BAT_Tiny_AD_AMTB{
	meta:
		description = "Trojan:BAT/Tiny.AD!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_80_0 = {73 74 61 74 78 2e 65 78 65 } //statx.exe  2
		$a_80_1 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 41 63 63 65 73 73 6f 72 69 65 73 5c 62 6a 2e 65 78 65 } //C:\Program Files\Windows NT\Accessories\bj.exe  1
		$a_80_2 = {68 74 74 70 3a 2f 2f 31 34 2e 35 35 2e 31 30 37 2e 31 30 } //http://14.55.107.10  2
		$a_80_3 = {73 74 61 74 78 2e 70 64 62 } //statx.pdb  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*2+(#a_80_3  & 1)*1) >=5
 
}