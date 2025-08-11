
rule Trojan_Win32_LummaStealer_MBX_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.MBX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {65 6a 62 61 6c 62 61 6b 6f 70 6c 63 68 6c 67 68 65 63 64 61 6c 6d 65 65 65 61 6a 6e 69 6d 68 6d } //1 ejbalbakoplchlghecdalmeeeajnimhm
		$a_01_1 = {61 65 62 6c 66 64 6b 68 68 68 64 63 64 6a 70 69 66 68 68 62 64 69 6f 6a 70 6c 66 6a 6e 63 6f 61 } //1 aeblfdkhhhdcdjpifhhbdiojplfjncoa
		$a_01_2 = {6a 6e 6c 67 61 6d 65 63 62 70 6d 62 61 6a 6a 66 68 6d 6d 6d 6c 68 65 6a 6b 65 6d 65 6a 64 6d 61 } //1 jnlgamecbpmbajjfhmmmlhejkemejdma
		$a_01_3 = {64 6c 63 6f 62 70 6a 69 69 67 70 69 6b 6f 6f 62 6f 68 6d 61 62 65 68 68 6d 68 66 6f 6f 64 62 62 } //1 dlcobpjiigpikoobohmabehhmhfoodbb
		$a_01_4 = {6a 67 61 61 69 6d 61 6a 69 70 62 70 64 6f 67 70 64 67 6c 68 61 70 68 6c 64 61 6b 69 6b 67 65 66 } //1 jgaaimajipbpdogpdglhaphldakikgef
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}