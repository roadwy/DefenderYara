
rule Trojan_Win32_LummaStealer_DA_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 06 00 00 "
		
	strings :
		$a_81_0 = {3c 48 54 41 3a 41 50 50 4c 49 43 41 54 49 4f 4e 20 69 63 6f 6e 3d 22 23 22 20 57 49 4e 44 4f 57 53 54 41 54 45 3d 22 6e 6f 72 6d 61 6c 22 20 53 48 4f 57 49 4e 54 41 53 4b 42 41 52 3d 22 6e 6f 22 20 53 59 53 4d 45 4e 55 3d 22 6e 6f 22 20 43 41 50 54 49 4f 4e 3d 22 6e 6f 22 20 42 4f 52 44 45 52 3d 22 6e 6f 6e 65 22 20 53 43 52 4f 4c 4c 3d 22 6e 6f 22 } //20 <HTA:APPLICATION icon="#" WINDOWSTATE="normal" SHOWINTASKBAR="no" SYSMENU="no" CAPTION="no" BORDER="none" SCROLL="no"
		$a_81_1 = {3c 48 54 41 3a 41 50 50 4c 49 43 41 54 49 4f 4e 20 43 41 50 54 49 4f 4e 20 3d 20 22 6e 6f 22 20 57 49 4e 44 4f 57 53 54 41 54 45 20 3d 20 22 6d 69 6e 69 6d 69 7a 65 22 20 53 48 4f 57 49 4e 54 41 53 4b 42 41 52 20 3d 20 22 6e 6f 22 } //20 <HTA:APPLICATION CAPTION = "no" WINDOWSTATE = "minimize" SHOWINTASKBAR = "no"
		$a_81_2 = {77 69 6e 64 6f 77 2e 63 6c 6f 73 65 28 29 3b } //1 window.close();
		$a_03_3 = {65 00 76 00 61 00 6c 00 28 00 [0-0f] 29 00 } //1
		$a_03_4 = {65 76 61 6c 28 [0-0f] 29 } //1
		$a_81_5 = {3c 2f 73 63 72 69 70 74 3e } //1 </script>
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*20+(#a_81_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_81_5  & 1)*1) >=23
 
}