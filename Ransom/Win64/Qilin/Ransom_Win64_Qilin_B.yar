
rule Ransom_Win64_Qilin_B{
	meta:
		description = "Ransom:Win64/Qilin.B,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 09 00 00 "
		
	strings :
		$a_01_0 = {2d 44 41 54 41 2e 74 78 74 } //1 -DATA.txt
		$a_01_1 = {45 6e 63 72 79 70 74 69 6f 6e 20 77 69 74 68 6f 75 74 20 6e 6f 74 65 73 } //1 Encryption without notes
		$a_01_2 = {53 6b 69 70 20 65 6e 63 72 79 70 74 69 6f 6e 20 6f 66 20 6e 65 74 77 6f 72 6b 20 64 61 74 61 } //1 Skip encryption of network data
		$a_01_3 = {53 65 74 73 20 74 68 65 20 70 61 74 68 20 74 6f 20 74 68 65 20 66 69 6c 65 20 6f 72 20 64 69 72 65 63 74 6f 72 79 20 74 6f 20 62 65 20 65 6e 63 72 79 70 74 65 64 } //1 Sets the path to the file or directory to be encrypted
		$a_01_4 = {35 35 37 33 36 31 36 37 36 35 33 41 32 30 37 30 37 33 36 35 37 38 36 35 36 33 } //1 55736167653A20707365786563
		$a_01_5 = {5b 2a 2e 65 78 65 2a 2e 45 58 45 2a 2e 44 4c 4c 2a 2e 69 6e 69 2a 2e 69 6e 66 2a 2e 70 6f 6c 2a 2e 63 6d 64 2a 2e 70 73 31 2a 2e 76 62 73 2a 2e 62 61 74 2a 2e 70 61 67 65 66 69 6c 65 2e 73 79 73 2a } //1 [*.exe*.EXE*.DLL*.ini*.inf*.pol*.cmd*.ps1*.vbs*.bat*.pagefile.sys*
		$a_01_6 = {73 71 6c 64 6f 63 72 74 66 78 6c 73 6a 70 67 6a 70 65 67 70 6e 67 67 69 66 77 65 62 70 74 69 66 66 70 73 64 72 61 77 62 6d 70 70 64 66 64 6f 63 78 64 6f 63 6d 64 6f 74 78 64 6f 74 6d 6f 64 74 78 6c 73 78 78 6c 73 6d 78 6c 74 } //1 sqldocrtfxlsjpgjpegpnggifwebptiffpsdrawbmppdfdocxdocmdotxdotmodtxlsxxlsmxlt
		$a_01_7 = {25 69 20 69 6e 20 28 27 73 63 20 71 75 65 72 79 20 73 74 61 74 65 5e 3d 20 61 6c 6c 20 5e 7c 20 66 69 6e 64 73 74 72 20 2f 49 20 27 29 20 64 6f 20 73 63 20 73 74 6f 70 20 25 69 } //1 %i in ('sc query state^= all ^| findstr /I ') do sc stop %i
		$a_01_8 = {7c 20 46 6f 72 45 61 63 68 2d 4f 62 6a 65 63 74 20 7b 20 53 74 6f 70 2d 56 4d 20 2d 4e 61 6d 65 20 24 5f 2e 4e 61 6d 65 20 2d 46 6f 72 63 65 20 2d 43 6f 6e 66 69 72 6d 3a 24 66 61 6c 73 65 } //1 | ForEach-Object { Stop-VM -Name $_.Name -Force -Confirm:$false
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=7
 
}