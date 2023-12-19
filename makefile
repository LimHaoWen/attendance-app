build :
	go build -o bin/attendanceapp

run : build
	./bin/attendanceapp

clean :
	rm -rf ./bin/attendancetaking

re : clean run